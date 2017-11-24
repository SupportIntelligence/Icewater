
rule m3e9_33945ab9c9800b16
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.33945ab9c9800b16"
     cluster="m3e9.33945ab9c9800b16"
     cluster_size="6"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="regrun ludbaruma tinba"
     md5_hashes="['09630f875676f3d7f9740456b0394151','8e14c462ebd7ead5c4777811821ad38f','cef5f59cf6199df825ae9b02f6229166']"

   strings:
      $hex_string = { debd3ebcf87c12ffcc869b91fe1eb4d13c8197ef66edbe4ffb0cc5eae793c4eb99549264a970f167c75ca1fc2e6d79576df975cf2789d74bd9f2f45a3f2d7faa }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
