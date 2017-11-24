
rule k3e9_2b14e9c534264cb2
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.2b14e9c534264cb2"
     cluster="k3e9.2b14e9c534264cb2"
     cluster_size="5"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="tinba crypt vbkrypt"
     md5_hashes="['4e8949c6452bac37294c7488890c31e5','56af2551d8ccf26f4345e71ef0865ec3','b83820ed1589651a0fefefffe9cec5df']"

   strings:
      $hex_string = { aa182002069861fa5163a74c6bccb51129c705baf6d0d2da761cc374268bded45cad8db4c500d39be6712d96f7f5f95234eee610c8224a1e0ed98092b3211b0a }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
