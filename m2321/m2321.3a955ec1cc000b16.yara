
rule m2321_3a955ec1cc000b16
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.3a955ec1cc000b16"
     cluster="m2321.3a955ec1cc000b16"
     cluster_size="28"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="regrun ludbaruma emotet"
     md5_hashes="['041362ee4870ba1aaeafe699d63a0e89','051a60a7ee295e65aa60fc2d4845f10b','8d9ee60be8e91f02302237fb463bd1f8']"

   strings:
      $hex_string = { 5c71ecf6894d4a25eee9bb128f572a3d10898349c5313e7cb79295a1be0406af1b5815873740439d47f75b5ea3fec23f632b59ebdaea66bf1eae560e17dd4e38 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
