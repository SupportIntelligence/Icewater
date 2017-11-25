
rule j3f0_21b4be48fee31912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j3f0.21b4be48fee31912"
     cluster="j3f0.21b4be48fee31912"
     cluster_size="7"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171121"
     license = "RIL-1.0 [Rick's Internet License] "
     family="razy malicious malob"
     md5_hashes="['0b5139c0c681bd33984586344564adaa','0f81ad4c0ceda8c0c6778bf5556c1636','db09e3ab6340efbdc219225bee86bdab']"

   strings:
      $hex_string = { 721d8b3989382bf203c203ca3bf273f285f674148a11881040414e75f7eb098a11881040414e75f70fb6314183fe1073570fb611c1ea02c1e6068db432010700 }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
