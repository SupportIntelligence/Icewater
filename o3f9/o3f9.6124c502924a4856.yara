
rule o3f9_6124c502924a4856
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o3f9.6124c502924a4856"
     cluster="o3f9.6124c502924a4856"
     cluster_size="31"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="lyposit zusy ransom"
     md5_hashes="['06d7c3f41d8de1ccf9d20524c1d699f3','14f523a73785486be19a74e74b24fbc4','b201835c36b009bd4b234f9509c30d66']"

   strings:
      $hex_string = { cb0ff6757a04c5b5e483bc926d146e9598e876bb978a5ea826019128d8afd2feeac689a7e54ef1fbd6a37f0671a5cf5be3e010c1307832ad8fb34af35f48c0bf }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
