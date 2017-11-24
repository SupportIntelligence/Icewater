
rule n3fa_119912b9c8800b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3fa.119912b9c8800b12"
     cluster="n3fa.119912b9c8800b12"
     cluster_size="286"
     filetype = "PE32+ executable (DLL) (GUI) x86-64"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="dangerousobject fari kryptik"
     md5_hashes="['01483875dd2b0c8c2c9ada9ad62540ed','01ab22243c98a71da517ce5842479d20','0e9674eb1a81c2d242d52a7d3cf8161d']"

   strings:
      $hex_string = { bedbebe0f65c4486c0586ca0d9b3050ebf2b60de233acb9ad65091bc17e8ddd457277941385bb472bd0c1be69b4c519c2d6d5f4e0f377f3c1c122a08a5631fd3 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
