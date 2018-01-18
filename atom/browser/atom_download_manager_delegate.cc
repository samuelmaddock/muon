// Copyright (c) 2015 GitHub, Inc.
// Use of this source code is governed by the MIT license that can be
// found in the LICENSE file.

#include "atom/browser/atom_download_manager_delegate.h"

#include <string>

#include "atom/browser/api/atom_api_download_item.h"
#include "atom/browser/native_window.h"
#include "atom/browser/ui/file_dialog.h"
#include "atom/browser/ui/message_box.h"
#include "base/bind.h"
#include "base/files/file_util.h"
#include "chrome/browser/browser_process.h"
#include "chrome/browser/download/download_completion_blocker.h"
#include "chrome/browser/download/download_item_model.h"
#include "chrome/browser/profiles/profile.h"
#include "chrome/browser/safe_browsing/download_protection/download_protection_util.h"
#include "chrome/browser/safe_browsing/safe_browsing_service.h"
#include "chrome/common/pref_names.h"
#include "chrome/common/safe_browsing/file_type_policies.h"
#include "chrome/grit/generated_resources.h"
#include "components/prefs/pref_service.h"
#include "content/public/browser/browser_context.h"
#include "content/public/browser/browser_thread.h"
#include "content/public/browser/download_danger_type.h"
#include "content/public/browser/download_manager.h"
#include "net/base/filename_util.h"
#include "ui/base/l10n/l10n_util.h"

namespace atom {

namespace {

using content::BrowserThread;
using content::DownloadItem;
using content::DownloadManager;
using safe_browsing::DownloadFileType;
using safe_browsing::DownloadProtectionService;

#if defined(FULL_SAFE_BROWSING)

const base::string16 safeBrowsingError = base::ASCIIToUTF16("Malware Download");
const base::string16 safeBrowsingContent
                        = base::ASCIIToUTF16("Downloading Malicious Content");

// String pointer used for identifying safebrowing data associated with
// a download item.
const char kSafeBrowsingUserDataKey[] = "Safe Browsing ID";

// The state of a safebrowsing check.
class SafeBrowsingState : public DownloadCompletionBlocker {
 public:
  SafeBrowsingState() {}
  ~SafeBrowsingState() override;

 private:
  DISALLOW_COPY_AND_ASSIGN(SafeBrowsingState);
};

SafeBrowsingState::~SafeBrowsingState() {}

#endif  // FULL_SAFE_BROWSING

// Used with GetPlatformDownloadPath() to indicate which platform path to
// return.
enum PlatformDownloadPathType {
  // Return the platform specific target path.
  PLATFORM_TARGET_PATH,

  // Return the platform specific current path. If the download is in-progress
  // and the download location is a local filesystem path, then
  // GetPlatformDownloadPath will return the path to the intermediate file.
  PLATFORM_CURRENT_PATH
};

base::FilePath GetPlatformDownloadPath(Profile* profile,
                                       const DownloadItem* download,
                                       PlatformDownloadPathType path_type) {
  if (path_type == PLATFORM_TARGET_PATH)
    return download->GetTargetFilePath();
  return download->GetFullPath();
}

// Reason for why danger type is DOWNLOAD_DANGER_TYPE_DANGEROUS_FILE.
// Used by "Download.DangerousFile.Reason" UMA metric.
// Do not change the ordering or remove items.
enum DangerousFileReason {
  SB_NOT_AVAILABLE = 0,
  SB_RETURNS_UNKOWN = 1,
  SB_RETURNS_SAFE = 2,
  DANGEROUS_FILE_REASON_MAX
};

#if defined(FULL_SAFE_BROWSING)
void CheckDownloadUrlDone(
    const DownloadTargetDeterminerDelegate::CheckDownloadUrlCallback& callback,
    safe_browsing::DownloadCheckResult result) {
  content::DownloadDangerType danger_type;
  if (result != safe_browsing::DownloadCheckResult::SAFE &&
      result != safe_browsing::DownloadCheckResult::UNKNOWN) {
    danger_type = content::DOWNLOAD_DANGER_TYPE_DANGEROUS_URL;
  } else {
    danger_type = content::DOWNLOAD_DANGER_TYPE_NOT_DANGEROUS;
  }
  callback.Run(danger_type);
}
#endif  // FULL_SAFE_BROWSING

const DownloadPathReservationTracker::FilenameConflictAction
    kDefaultPlatformConflictAction = DownloadPathReservationTracker::UNIQUIFY;

}  // namespace

void AtomDownloadManagerDelegate::SetDownloadManager(DownloadManager* dm) {
  download_manager_ = dm;

  safe_browsing::SafeBrowsingService* sb_service =
      g_browser_process->safe_browsing_service();
  if (sb_service) {
    // Include this download manager in the set monitored by safe browsing.
    sb_service->AddDownloadManager(dm);
  }
}

// static
void AtomDownloadManagerDelegate::DisableSafeBrowsing(DownloadItem* item) {
  DCHECK_CURRENTLY_ON(BrowserThread::UI);
#if defined(FULL_SAFE_BROWSING)
  SafeBrowsingState* state = static_cast<SafeBrowsingState*>(
      item->GetUserData(&kSafeBrowsingUserDataKey));
  if (!state) {
    state = new SafeBrowsingState();
    item->SetUserData(&kSafeBrowsingUserDataKey, base::WrapUnique(state));
  }
  state->CompleteDownload();
#endif
}

bool AtomDownloadManagerDelegate::IsDownloadReadyForCompletion(
    DownloadItem* item,
    const base::Closure& internal_complete_callback) {
  DCHECK_CURRENTLY_ON(BrowserThread::UI);
#if defined(FULL_SAFE_BROWSING)
  SafeBrowsingState* state = static_cast<SafeBrowsingState*>(
      item->GetUserData(&kSafeBrowsingUserDataKey));
  if (!state) {
    // Begin the safe browsing download protection check.
    DownloadProtectionService* service = GetDownloadProtectionService();
    if (service) {
      DVLOG(2) << __func__ << "() Start SB download check for download = "
               << item->DebugString(false);
      state = new SafeBrowsingState();
      state->set_callback(internal_complete_callback);
      item->SetUserData(&kSafeBrowsingUserDataKey, base::WrapUnique(state));
      service->CheckClientDownload(
          item,
          base::Bind(&AtomDownloadManagerDelegate::CheckClientDownloadDone,
                     weak_ptr_factory_.GetWeakPtr(),
                     item->GetId()));
      return false;
    }

    // In case the service was disabled between the download starting and now,
    // we need to restore the danger state.
    content::DownloadDangerType danger_type = item->GetDangerType();
    if (DownloadItemModel(item).GetDangerLevel() !=
            DownloadFileType::NOT_DANGEROUS &&
        (danger_type == content::DOWNLOAD_DANGER_TYPE_NOT_DANGEROUS ||
         danger_type ==
             content::DOWNLOAD_DANGER_TYPE_MAYBE_DANGEROUS_CONTENT)) {
      DVLOG(2) << __func__
               << "() SB service disabled. Marking download as DANGEROUS FILE";
      if (ShouldBlockFile(content::DOWNLOAD_DANGER_TYPE_DANGEROUS_FILE)) {
        item->OnContentCheckCompleted(
            // Specifying a dangerous type here would take precendence over the
            // blocking of the file.
            content::DOWNLOAD_DANGER_TYPE_NOT_DANGEROUS,
            content::DOWNLOAD_INTERRUPT_REASON_FILE_BLOCKED);
      } else {
        item->OnContentCheckCompleted(
            content::DOWNLOAD_DANGER_TYPE_DANGEROUS_FILE,
            content::DOWNLOAD_INTERRUPT_REASON_NONE);
      }
      content::BrowserThread::PostTask(content::BrowserThread::UI, FROM_HERE,
                                       internal_complete_callback);
      return false;
    }
  } else if (!state->is_complete()) {
    // Don't complete the download until we have an answer.
    state->set_callback(internal_complete_callback);
    return false;
  }

#endif
  return true;
}

bool AtomDownloadManagerDelegate::GenerateFileHash() {
#if defined(FULL_SAFE_BROWSING)
  return g_browser_process->safe_browsing_service()->DownloadBinHashNeeded();
#else
  return false;
#endif
}

void AtomDownloadManagerDelegate::SanitizeSavePackageResourceName(
    base::FilePath* filename) {
  safe_browsing::FileTypePolicies* file_type_policies =
      safe_browsing::FileTypePolicies::GetInstance();

  if (file_type_policies->GetFileDangerLevel(*filename) ==
      safe_browsing::DownloadFileType::NOT_DANGEROUS)
    return;

  base::FilePath default_filename = base::FilePath::FromUTF8Unsafe(
      l10n_util::GetStringUTF8(IDS_DEFAULT_DOWNLOAD_FILENAME));
  *filename = filename->AddExtension(default_filename.BaseName().value());
}

DownloadProtectionService*
    AtomDownloadManagerDelegate::GetDownloadProtectionService() {
  DCHECK_CURRENTLY_ON(BrowserThread::UI);
#if defined(FULL_SAFE_BROWSING)
  safe_browsing::SafeBrowsingService* sb_service =
      g_browser_process->safe_browsing_service();
  if (sb_service && sb_service->download_protection_service()) {
    return sb_service->download_protection_service();
  }
#endif
  return NULL;
}

void AtomDownloadManagerDelegate::ShouldCompleteDownloadInternal(
    uint32_t download_id,
    const base::Closure& user_complete_callback) {
  DownloadItem* item = download_manager_->GetDownload(download_id);
  if (!item)
    return;
  if (ShouldCompleteDownload(item, user_complete_callback))
    user_complete_callback.Run();
}

bool AtomDownloadManagerDelegate::ShouldCompleteDownload(
    DownloadItem* item,
    const base::Closure& user_complete_callback) {
  return IsDownloadReadyForCompletion(item, base::Bind(
      &AtomDownloadManagerDelegate::ShouldCompleteDownloadInternal,
      weak_ptr_factory_.GetWeakPtr(), item->GetId(), user_complete_callback));
}

void AtomDownloadManagerDelegate::CheckDownloadUrl(
    DownloadItem* download,
    const base::FilePath& suggested_path,
    const CheckDownloadUrlCallback& callback) {
  DCHECK_CURRENTLY_ON(BrowserThread::UI);

#if defined(FULL_SAFE_BROWSING)
  safe_browsing::DownloadProtectionService* service =
      GetDownloadProtectionService();
  if (service) {
    DVLOG(2) << __func__ << "() Start SB URL check for download = "
             << download->DebugString(false);
    service->CheckDownloadUrl(download,
                              base::Bind(&CheckDownloadUrlDone, callback));
    return;
  }
#endif
  callback.Run(content::DOWNLOAD_DANGER_TYPE_NOT_DANGEROUS);
}

#if defined(FULL_SAFE_BROWSING)
void AtomDownloadManagerDelegate::CheckClientDownloadDone(
    uint32_t download_id,
    safe_browsing::DownloadCheckResult result) {
  DownloadItem* item = download_manager_->GetDownload(download_id);
  if (!item || (item->GetState() != DownloadItem::IN_PROGRESS))
    return;

  DVLOG(2) << __func__ << "() download = " << item->DebugString(false)
           << " verdict = " << static_cast<int>(result);
  // We only mark the content as being dangerous if the download's safety state
  // has not been set to DANGEROUS yet.  We don't want to show two warnings.
  if (item->GetDangerType() == content::DOWNLOAD_DANGER_TYPE_NOT_DANGEROUS ||
      item->GetDangerType() ==
      content::DOWNLOAD_DANGER_TYPE_MAYBE_DANGEROUS_CONTENT) {
    content::DownloadDangerType danger_type =
        content::DOWNLOAD_DANGER_TYPE_NOT_DANGEROUS;
    switch (result) {
      case safe_browsing::DownloadCheckResult::UNKNOWN:
        // The check failed or was inconclusive.
        if (DownloadItemModel(item).GetDangerLevel() !=
            DownloadFileType::NOT_DANGEROUS) {
          danger_type = content::DOWNLOAD_DANGER_TYPE_DANGEROUS_FILE;
        }
        break;
      case safe_browsing::DownloadCheckResult::SAFE:
        // If this file type require explicit consent, then set the danger type
        // to DANGEROUS_FILE so that the user be required to manually vet
        // whether the download is intended or not.
        if (DownloadItemModel(item).GetDangerLevel() ==
            DownloadFileType::DANGEROUS) {
          danger_type = content::DOWNLOAD_DANGER_TYPE_DANGEROUS_FILE;
        }
        break;
      case safe_browsing::DownloadCheckResult::DANGEROUS:
        danger_type = content::DOWNLOAD_DANGER_TYPE_DANGEROUS_CONTENT;
        break;
      case safe_browsing::DownloadCheckResult::UNCOMMON:
        danger_type = content::DOWNLOAD_DANGER_TYPE_UNCOMMON_CONTENT;
        break;
      case safe_browsing::DownloadCheckResult::DANGEROUS_HOST:
        danger_type = content::DOWNLOAD_DANGER_TYPE_DANGEROUS_HOST;
        break;
      case safe_browsing::DownloadCheckResult::POTENTIALLY_UNWANTED:
        danger_type = content::DOWNLOAD_DANGER_TYPE_POTENTIALLY_UNWANTED;
        break;
    }
    DCHECK_NE(danger_type,
              content::DOWNLOAD_DANGER_TYPE_MAYBE_DANGEROUS_CONTENT);

    if (danger_type != content::DOWNLOAD_DANGER_TYPE_NOT_DANGEROUS) {
      if (ShouldBlockFile(danger_type)) {
        item->OnContentCheckCompleted(
            danger_type,
            content::DOWNLOAD_INTERRUPT_REASON_FILE_BLOCKED);
      } else {
        item->OnContentCheckCompleted(danger_type,
                                      content::DOWNLOAD_INTERRUPT_REASON_NONE);
      }
    }
  }

  SafeBrowsingState* state = static_cast<SafeBrowsingState*>(
      item->GetUserData(&kSafeBrowsingUserDataKey));
  state->CompleteDownload();
}
#endif  // FULL_SAFE_BROWSING

bool AtomDownloadManagerDelegate::ShouldBlockFile(
    content::DownloadDangerType danger_type) const {
      return (danger_type == content::DOWNLOAD_DANGER_TYPE_DANGEROUS_CONTENT ||
              danger_type == content::DOWNLOAD_DANGER_TYPE_DANGEROUS_FILE ||
              danger_type == content::DOWNLOAD_DANGER_TYPE_DANGEROUS_URL);
}

void AtomDownloadManagerDelegate::MaybeSendDangerousDownloadOpenedReport(
    DownloadItem* download,
    bool show_download_in_folder) {
#if defined(FULL_SAFE_BROWSING)
  safe_browsing::DownloadProtectionService* service =
      GetDownloadProtectionService();
  if (service) {
    service->MaybeSendDangerousDownloadOpenedReport(download,
                                                    show_download_in_folder);
  }
#endif
}

AtomDownloadManagerDelegate::AtomDownloadManagerDelegate(
    content::DownloadManager* manager)
    : download_manager_(manager),
      weak_ptr_factory_(this) {}

AtomDownloadManagerDelegate::~AtomDownloadManagerDelegate() {
  if (download_manager_) {
    DCHECK_EQ(static_cast<content::DownloadManagerDelegate*>(this),
              download_manager_->GetDelegate());
    download_manager_->SetDelegate(nullptr);
    download_manager_ = nullptr;
  }
}

void AtomDownloadManagerDelegate::GetItemSavePath(content::DownloadItem* item,
                                                  base::FilePath* path) {
  v8::Isolate* isolate = v8::Isolate::GetCurrent();
  v8::Locker locker(isolate);
  v8::HandleScope handle_scope(isolate);
  api::DownloadItem* download = api::DownloadItem::FromWrappedClass(isolate,
                                                                    item);
  if (download && !download->GetSavePath().empty())
    *path = download->GetSavePath();
}

void AtomDownloadManagerDelegate::DetermineLocalPath(
    DownloadItem* download,
    const base::FilePath& virtual_path,
    const DownloadTargetDeterminerDelegate::LocalPathCallback& callback) {
  DCHECK_CURRENTLY_ON(BrowserThread::UI);
#if defined(OS_CHROMEOS)
  drive::DownloadHandler* drive_download_handler =
      drive::DownloadHandler::GetForProfile(profile_);
  if (drive_download_handler) {
    drive_download_handler->SubstituteDriveDownloadPath(
        virtual_path, download, callback);
    return;
  }
#endif
  callback.Run(virtual_path);
}

void AtomDownloadManagerDelegate::OnDownloadTargetDetermined(
    int32_t download_id,
    const content::DownloadTargetCallback& callback,
    std::unique_ptr<DownloadTargetInfo> target_info) {
  DCHECK_CURRENTLY_ON(content::BrowserThread::UI);
  auto item = download_manager_->GetDownload(download_id);
  if (!item)
    return;

  if (ShouldBlockFile(target_info->danger_type)) {
    item->OnContentCheckCompleted(
        // Specifying a dangerous type here would take precendence over the
        // blocking of the file.
        content::DOWNLOAD_DANGER_TYPE_NOT_DANGEROUS,
        content::DOWNLOAD_INTERRUPT_REASON_FILE_BLOCKED);
  } else {
    item->OnContentCheckCompleted(
        content::DOWNLOAD_DANGER_TYPE_DANGEROUS_FILE,
        content::DOWNLOAD_INTERRUPT_REASON_NONE);
  }

  v8::Isolate* isolate = v8::Isolate::GetCurrent();
  v8::Locker locker(isolate);
  v8::HandleScope handle_scope(isolate);
  api::DownloadItem* download_item = api::DownloadItem::FromWrappedClass(
      isolate, item);

  if (!download_item)
    download_item = atom::api::DownloadItem::Create(isolate, item).get();

  base::FilePath path = target_info->target_path;

  NativeWindow* window = nullptr;
  content::WebContents* web_contents = item->GetWebContents();
  auto relay = web_contents ? NativeWindowRelay::FromWebContents(web_contents)
                            : nullptr;
  if (relay)
    window = relay->window.get();

  GetItemSavePath(item, &path);

  // Show save dialog if save path was not set already on item
  file_dialog::DialogSettings settings;
  settings.parent_window = window;
  settings.title = item->GetURL().spec();
  settings.default_path = path;
  if (path.empty() && file_dialog::ShowSaveDialog(settings, &path)) {
    // Remember the last selected download directory.
    Profile* profile = static_cast<Profile*>(
        download_manager_->GetBrowserContext());
    profile->GetPrefs()->SetFilePath(prefs::kDownloadDefaultDirectory,
                                          path.DirName());
  }

  if (path.empty())
    item->Remove();

  if (download_item)
    download_item->SetSavePath(path);

  callback.Run(path,
               content::DownloadItem::TARGET_DISPOSITION_PROMPT,
               target_info->danger_type, path,
               target_info->result);
}

void AtomDownloadManagerDelegate::Shutdown() {
  weak_ptr_factory_.InvalidateWeakPtrs();
  download_manager_ = nullptr;
}

bool AtomDownloadManagerDelegate::DetermineDownloadTarget(
    DownloadItem* download,
    const content::DownloadTargetCallback& callback) {
  DCHECK_CURRENTLY_ON(content::BrowserThread::UI);

  Profile* browser_context = static_cast<Profile*>(
      download_manager_->GetBrowserContext());
  base::FilePath default_download_path(browser_context->GetPrefs()->GetFilePath(
      prefs::kDownloadDefaultDirectory));

  DownloadPathReservationTracker::FilenameConflictAction conflict_action =
      DownloadPathReservationTracker::OVERWRITE;
  base::FilePath virtual_path = download->GetForcedFilePath();

  if (virtual_path.empty()) {
    std::string suggested_filename(download->GetSuggestedFilename());
    if (suggested_filename.empty() &&
        download->GetMimeType() == "application/x-x509-user-cert") {
      suggested_filename = "user.crt";
    }

    base::FilePath generated_filename = net::GenerateFileName(
        download->GetURL(),
        download->GetContentDisposition(),
        std::string(),
        suggested_filename,
        download->GetMimeType(),
        std::string());

    conflict_action = kDefaultPlatformConflictAction;
    virtual_path = default_download_path.Append(generated_filename);
  }

  DownloadTargetDeterminer::CompletionCallback target_determined_callback =
      base::Bind(&AtomDownloadManagerDelegate::OnDownloadTargetDetermined,
                 weak_ptr_factory_.GetWeakPtr(),
                 download->GetId(),
                 callback);

  DownloadTargetDeterminer::Start(
      download,
      virtual_path,
      kDefaultPlatformConflictAction, nullptr, this,
      target_determined_callback);

  return true;
}

void AtomDownloadManagerDelegate::ReserveVirtualPath(
    content::DownloadItem* download,
    const base::FilePath& virtual_path,
    bool create_directory,
    DownloadPathReservationTracker::FilenameConflictAction conflict_action,
    const ReservedPathCallback& callback) {
      Profile* browser_context = static_cast<Profile*>(
          download_manager_->GetBrowserContext());
      base::FilePath default_download_path(
        browser_context->GetPrefs()->GetFilePath(
          prefs::kDownloadDefaultDirectory));

      DownloadPathReservationTracker::GetReservedPath(
          download,
          virtual_path,
          default_download_path,
          true,
          conflict_action,
          callback);
}

bool AtomDownloadManagerDelegate::IsOpenInBrowserPreferreredForFile(
    const base::FilePath& path) {
#if defined(OS_WIN) || defined(OS_LINUX) || defined(OS_MACOSX)
  if (path.MatchesExtension(FILE_PATH_LITERAL(".pdf"))) {
    return true;
  }
#endif
}

bool AtomDownloadManagerDelegate::ShouldOpenDownload(
    content::DownloadItem* download,
    const content::DownloadOpenDelayedCallback& callback) {
  return true;
}

void AtomDownloadManagerDelegate::GetNextId(
    const content::DownloadIdCallback& callback) {
  static uint32_t next_id = content::DownloadItem::kInvalidId + 1;
  callback.Run(next_id++);
}

}  // namespace atom
