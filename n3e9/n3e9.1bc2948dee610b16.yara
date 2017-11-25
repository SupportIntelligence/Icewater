
rule n3e9_1bc2948dee610b16
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.1bc2948dee610b16"
     cluster="n3e9.1bc2948dee610b16"
     cluster_size="27"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="malicious dealply classic"
     md5_hashes="['12c7393961f105804bcf624ce87b338d','13d9d10e406b3c58a062b62a36e79d07','99e03b8359eda86a83b7cf3484f11c0b']"

   strings:
      $hex_string = { 00720063006800050041007000720069006c0003004d006100790004004a0075006e00650004004a0075006c0079000600410075006700750073007400090053 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
