
rule k2321_2b5ceccd32464aba
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.2b5ceccd32464aba"
     cluster="k2321.2b5ceccd32464aba"
     cluster_size="5"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="tinba crypt emotet"
     md5_hashes="['0c7e248c5fa7e4dbf097109b15cbac06','114ac552cccbb66505b02a737a8a0f16','f99115c6bf3883caf5ee6f977bf9be96']"

   strings:
      $hex_string = { 5da5dcb5e418c4e2512a97f37636a4cf42d969a8eb0c663c55b614c8e59e73402e043a71d7881290670024c6335361791feeba4f6c87fd0994e7daed1f0e7d03 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
