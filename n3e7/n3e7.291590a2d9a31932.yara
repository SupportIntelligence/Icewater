
rule n3e7_291590a2d9a31932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e7.291590a2d9a31932"
     cluster="n3e7.291590a2d9a31932"
     cluster_size="37"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="vbkrypt qmlfrt injector"
     md5_hashes="['25e72edd908d8eddc7649e901944aed2','4ba773fe930d13f9e8d0b1c98f290f0a','ac120872f2b90fe63c57a57a6762dfab']"

   strings:
      $hex_string = { 16e8f8b4ad1d74b10b657ea9c3a3b23ade4386b66a7b041b5199d395775fc02b8598395783338b0519ac2afe71c43f7872f7dad0c6d112314cef8ae4176f26e7 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
