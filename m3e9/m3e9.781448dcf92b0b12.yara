
rule m3e9_781448dcf92b0b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.781448dcf92b0b12"
     cluster="m3e9.781448dcf92b0b12"
     cluster_size="10"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="vobfus chinky vbkrypt"
     md5_hashes="['2289ff380d7ad3bc04cf945198c2ec02','a117642bcc47ad20f03cd08e791377ff','e6326cd6fc0263e33cc5a8b5b989752b']"

   strings:
      $hex_string = { 282a2e457eb7c07d7d655753520e1269ddf3f6f6f6f3d04623000000038b8b8b8cc0c1c6c6dbd9d94f403a31312d2d3031404f74b7c0b77d7d625551500d12b9 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
