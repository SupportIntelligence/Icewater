
rule m2377_239a96c9cc000b16
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2377.239a96c9cc000b16"
     cluster="m2377.239a96c9cc000b16"
     cluster_size="9"
     filetype = "HTML document"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit html script"
     md5_hashes="['42ccf87199fa3e7b25a17bcfa7bee062','5f50054297680ad42e5c500c39c2522b','e4632f46678e87d4f83547103a222ccf']"

   strings:
      $hex_string = { 2e7a5726cd958520cc98aabd6a38403d2cf8e4613966542bd3193f25aff5b84bd01497e92a9b2f777015a2516d827ce162f4bcfb0f91b2869fad166b7163c100 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
