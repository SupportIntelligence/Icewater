
rule n2321_5b18934bc6220b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n2321.5b18934bc6220b32"
     cluster="n2321.5b18934bc6220b32"
     cluster_size="106"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="small generickd upatre"
     md5_hashes="['0095ebf79eaed355028676f3552abae2','00db12560386094d1c5b9f61ac992359','2db64b8feb089d84f042ceb84a1c08cc']"

   strings:
      $hex_string = { c2fa4d04f9650be8ba22e457cd5c8435a37eeb4e62f7f8a88a81d8a737d09260db90066bbfc003df86f0338d44ad463d598899e394c6086eb7557900ead7183e }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
