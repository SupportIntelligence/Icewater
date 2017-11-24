
rule k3f1_13b294aad9eb1912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3f1.13b294aad9eb1912"
     cluster="k3f1.13b294aad9eb1912"
     cluster_size="7"
     filetype = "Zip archive data"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="androidos smssend trojansms"
     md5_hashes="['2f36fd0c0ab9843c3c72d1425e74434e','56ebda7357893772a30043bed4ca3125','eedc6abb6689bdfac29d80f7e6bd3d11']"

   strings:
      $hex_string = { 47775d60ad16d442f4ae72b539ac9a32301b6e898b8506e72c9eb7e5a55a368710b21ae9dff8f013b65fcdbdb1ce8a0474322927f6e87c4512d540ff98d0b9e3 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
