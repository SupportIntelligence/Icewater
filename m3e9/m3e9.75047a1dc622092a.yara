
rule m3e9_75047a1dc622092a
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.75047a1dc622092a"
     cluster="m3e9.75047a1dc622092a"
     cluster_size="5"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171119"
     license = "RIL-1.0 [Rick's Internet License] "
     family="virut prepender shodi"
     md5_hashes="['53ef013797e6be71678ff8074894020f','6e4aa503327cedb512ef5e3e09690082','7b668e103f62397d189df8cf564f3786']"

   strings:
      $hex_string = { 32804b06f3fba6e672e043de5b538dc6da3a2bb6c39faf639da717be295eac4205d4cf9590566136893bb459163134244a60ad97b7ef035a550c931e2847eba3 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
