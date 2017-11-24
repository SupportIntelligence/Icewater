
rule n3e9_339a6886dcbb0912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.339a6886dcbb0912"
     cluster="n3e9.339a6886dcbb0912"
     cluster_size="21"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="fileinfector gate aovhryb"
     md5_hashes="['1da51fdaa2031e46b7fee3fcdae56617','35e436a7524f2ca04aacae479e45912d','e213393edfdc7b1d6268c96a8f049daa']"

   strings:
      $hex_string = { ee18f18372e0493953a702b6ceb2c32ba0330c10e97170ec3da1edcc068457b411aed20ecd8a8cb0acbf5941cfca52ded920a317c5bc6b94ef66c16df96e56d6 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
