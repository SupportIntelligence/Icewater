import "hash"

rule k3e9_51a933069da31132
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.4 divinorum/0.992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.51a933069da31132"
     cluster="k3e9.51a933069da31132"
     cluster_size="6 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171031"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob virux"
     md5_hashes="['77a059c8f8ea34527c28260587c325fd', '9db89860b1db19329678da554287eca5', '52bf1a0f1993cada474b906cac9da6c9']"


   condition:
      uint16(0) == 0x5A4D and 
      filesize > 16384 and filesize < 65536 and 
      hash.md5(4096,1024) == "ad15aab32629fffb74cd0aec45ef7672"
}

