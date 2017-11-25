
rule m3f7_3a196a49c0000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3f7.3a196a49c0000b12"
     cluster="m3f7.3a196a49c0000b12"
     cluster_size="58"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="likejack faceliker html"
     md5_hashes="['00dc2327acc4909dc6354d5d26683aec','08a1f91c160cd38b0b804b9caec234be','51607921b215eae18d7ef2cc3a9c8b01']"

   strings:
      $hex_string = { 66756e6374696f6e28297b436c69636b4a61636b466253686f7728293b7d293b0a0909096a517565727928222e726174696e67626c6f636b22292e6d6f757365 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
