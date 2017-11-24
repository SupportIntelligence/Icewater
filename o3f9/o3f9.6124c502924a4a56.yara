
rule o3f9_6124c502924a4a56
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o3f9.6124c502924a4a56"
     cluster="o3f9.6124c502924a4a56"
     cluster_size="6"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="zusy lyposit malicious"
     md5_hashes="['0a2384c61be79a8d3e76c4559bd7f0d5','2596feae3808b56a7dfbcaa19852d6ca','d577e0201fd2bc27d5f1196c33fe0727']"

   strings:
      $hex_string = { cb0ff6757a04c5b5e483bc926d146e9598e876bb978a5ea826019128d8afd2feeac689a7e54ef1fbd6a37f0671a5cf5be3e010c1307832ad8fb34af35f48c0bf }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
