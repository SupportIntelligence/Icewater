
rule m3e9_1493eb26942b9912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.1493eb26942b9912"
     cluster="m3e9.1493eb26942b9912"
     cluster_size="319"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="malicious engine heuristic"
     md5_hashes="['00c5d0731bc07fdac0a263df9a5fb6a0','00dc748e7befe5f02fdaaaab57558358','0d5b7dffc9619f0b6e7492cbf743556c']"

   strings:
      $hex_string = { 8d46185750e8c6ccffff895e0483c40c33db89be1c02000043395de87651807dee008d45ee74218a480184c9741a0fb6d10fb608eb06804c0e1904413bca76f6 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
