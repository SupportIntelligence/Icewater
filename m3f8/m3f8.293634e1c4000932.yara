
rule m3f8_293634e1c4000932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3f8.293634e1c4000932"
     cluster="m3f8.293634e1c4000932"
     cluster_size="685"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="fakeinst androidos smsbot"
     md5_hashes="['a9033b2358fb8ae51a41bf57889c537383b06552','5d079762588e3aa0f4af118b2edbe73c908d3235','5bc96878e4714bddb38cbf414948f4934081ed54']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m3f8.293634e1c4000932"

   strings:
      $hex_string = { 4c69737400084170705468656d65000b4261736536342e6a61766100104275696c64436f6e6669672e6a6176610001430015434841525f53455155454e43455f }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
