
rule m3e9_16639291c8000112
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.16639291c8000112"
     cluster="m3e9.16639291c8000112"
     cluster_size="18906"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171109"
     license = "RIL-1.0 [Rick's Internet License] "
     family="tinba crypt emotet"
     md5_hashes="['001a95948567c83ff6285d6e7aac6947','0022320dad8ab27d481d20e825f9fb7c','00672ec6253d0e58dcdf5635cab0522d']"

   strings:
      $hex_string = { 56135b851f3710fbc15510285dee6b14a06d2099c765cc19e5d876656652582733e058b27a3f37a0f6189cf878384387204df53e694268583ddb3e53c287d526 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
