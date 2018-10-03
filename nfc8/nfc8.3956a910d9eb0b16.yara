
rule nfc8_3956a910d9eb0b16
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=nfc8.3956a910d9eb0b16"
     cluster="nfc8.3956a910d9eb0b16"
     cluster_size="3"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180911"
     license = "RIL-1.0 [Rick's Internet License]"
     family="svpeng koler slocker"
     md5_hashes="['07e6b41048f19ebf3331513e999b506db10b0ac4','2e7602f02fab429a25c481ec2812daae83ddc8ce','3c12e8e1693ee61e0808e20a9bc4a9f00a8a0f6f']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=nfc8.3956a910d9eb0b16"

   strings:
      $hex_string = { 15c54b0dbebc9ccadd018046add0d6cb260e16002807d1368a2efcbd7fbd736d046b501d420890ee09ec3f31a22dede61cdafe4d618b7ca1f5a9191394fb84b0 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
