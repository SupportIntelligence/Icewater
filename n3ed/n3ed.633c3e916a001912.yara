
rule n3ed_633c3e916a001912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3ed.633c3e916a001912"
     cluster="n3ed.633c3e916a001912"
     cluster_size="12"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="browsefox unwanted yontoo"
     md5_hashes="['274661cb9fee5a43bf0e91c952b58b41','2d297e75f52012f0fb03a9117f721be4','e57179ee6f47fbed190c29622a0bd4ab']"

   strings:
      $hex_string = { 02006675636f6d69700000000000000000003020000031200000000000000000000000d0800740000000000000000000000006000000050002006675636f6d69 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
