
rule k2377_3891576b8b4b4912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2377.3891576b8b4b4912"
     cluster="k2377.3891576b8b4b4912"
     cluster_size="7"
     filetype = "HTML document"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="script iframe iframeinject"
     md5_hashes="['08dc0ce843fa1f0188591adc98a79187','601d33f189a811485695c96a87366493','e083882d86a7d1ed2d883836ca5608a1']"

   strings:
      $hex_string = { 736f626f74c499203820677275646e6961203230313220726f6b752070727a7920e2809e434841434945204e412047524f4e4955e2809dc2a0206f646279c582 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
