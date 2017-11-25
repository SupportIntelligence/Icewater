
rule k3e9_1395a166dd839932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.1395a166dd839932"
     cluster="k3e9.1395a166dd839932"
     cluster_size="135"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="virut virtob virux"
     md5_hashes="['0633313962e287e7e457122708bf141e','063ea954c3aefb203b5d481aa93f4c44','7fd6bbd64df5ea03bcf78412f207c0f6']"

   strings:
      $hex_string = { 5c6acc4dba332b1bc4420a5732451496bdc29d408f3ef2efeda7b4fbb26f5e2f65d78e45be53031af5e4269b1275e8847677594fb119165dee47e60ac58c6989 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
