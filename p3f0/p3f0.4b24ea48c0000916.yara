
rule p3f0_4b24ea48c0000916
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=p3f0.4b24ea48c0000916"
     cluster="p3f0.4b24ea48c0000916"
     cluster_size="140"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ursu gamemodding heuristic"
     md5_hashes="['0258b11311ab113e7177edbc70ba3fd2','028f9193eec427bbb640387058b28c08','2846acdecb0b06fff2e66f9f991fc1e8']"

   strings:
      $hex_string = { d10dd365b7487f3331e5b5b9027df0e603f4868316cd9bf3729eed0cb06a4bb6698b32abfa0ee8a2be5914f6f215873827ae532493ea0bf16cdb018a685e8867 }

   condition:
      
      filesize > 4194304 and filesize < 16777216
      and $hex_string
}
