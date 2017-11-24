
rule m3e9_33134954d6c30916
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.33134954d6c30916"
     cluster="m3e9.33134954d6c30916"
     cluster_size="7"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="cerber gepys ransom"
     md5_hashes="['16e148a7f4dcdc13290086443dba4a61','5b742dce2baea3fdee0b548ab449c25a','f6e3e8d84f74ac8dbaa2c80a217b0fc9']"

   strings:
      $hex_string = { 02353f6c56b4e93bfd806e30727104a08c523c6b71a3c77d8e8b190fac1e213a97106286905c3369c35a3816ab7ff58f70b1c5c0b3d3b9f9cdbc1f173e8d63e4 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
