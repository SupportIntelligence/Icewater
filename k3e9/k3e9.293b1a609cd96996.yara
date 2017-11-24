
rule k3e9_293b1a609cd96996
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.293b1a609cd96996"
     cluster="k3e9.293b1a609cd96996"
     cluster_size="712"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="malicious installcore adinstall"
     md5_hashes="['00d6f33789b83d9ad601f70265dba89f','014f11938804fb698318a205800def3e','0862f4f281af22b81730bb0e231d2f4d']"

   strings:
      $hex_string = { 1674dbbe474898bfde990249202fdf657d9e2a75eaf1b15db71d5b0d6dc273a3383e3637764570f8c4da2df94da1d913cf6b1030fbe954a22860696606ae6277 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
