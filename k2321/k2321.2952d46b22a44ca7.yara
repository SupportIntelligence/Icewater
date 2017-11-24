
rule k2321_2952d46b22a44ca7
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.2952d46b22a44ca7"
     cluster="k2321.2952d46b22a44ca7"
     cluster_size="8"
     filetype = "PE32 executable (DLL) (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="graftor nitol ddos"
     md5_hashes="['05b4a1058acf2351a7112fe2c21df23b','072ae8c812896227af90396fb4f14d82','e128b386a7b46d430cb1863b7b9b8904']"

   strings:
      $hex_string = { 6a84e24d40ebf622526531b950bc1e1afd9b5e1d38ee2a0ca31711cd4a5f4277a4cf78c591de765c932d4fff5d472ab6b30bcc278c7c329dd51c3daba983a52f }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
