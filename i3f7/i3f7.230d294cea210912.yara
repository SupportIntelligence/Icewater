
rule i3f7_230d294cea210912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=i3f7.230d294cea210912"
     cluster="i3f7.230d294cea210912"
     cluster_size="52"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="html phishing phish"
     md5_hashes="['0399dcd5125680dedccde2ceb50aa3b4','0ba937edd4034bfe9775c35f29b4b11c','489a3f0335fdf84a7da325d36c79a48f']"

   strings:
      $hex_string = { 636861727365743d77696e646f77732d31323532223e0d0a3c7469746c653e457863656c204f6e6c696e65202d2030394b534a444a52343834333938344e4639 }

   condition:
      
      filesize > 1024 and filesize < 4096
      and $hex_string
}
