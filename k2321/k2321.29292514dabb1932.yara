
rule k2321_29292514dabb1932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.29292514dabb1932"
     cluster="k2321.29292514dabb1932"
     cluster_size="5"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="vobfus vbkrypt wbna"
     md5_hashes="['422020550bda2dc9de8b7bba125f1247','a8bb1c679b856b13f599eb8cea170c80','fbd45ba15db64f1799460384b5d251e2']"

   strings:
      $hex_string = { 279718c06e4e54e3cd89ea1de4e6c4a6f75b9e9de95ace3de25c7c0fde4b896cbeda9ceddd46c59671584a3e65b9e1213b552e13cfee93003862b2ad3f8b8784 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
