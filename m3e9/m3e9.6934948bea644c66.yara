
rule m3e9_6934948bea644c66
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.6934948bea644c66"
     cluster="m3e9.6934948bea644c66"
     cluster_size="6"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171111"
     license = "RIL-1.0 [Rick's Internet License] "
     family="virut virtob malicious"
     md5_hashes="['04e49072cac8c2e4e2a7462a998e95a0','2484b5ade6d0cf1fc44e2fe150410d2a','d072bf1cdd9c7a839658702dd7da94e0']"

   strings:
      $hex_string = { 5cbf777c8a4da53ed81c70cf743c270d064253caf54196e4b1e8169308a694d610b2dfc80d4995769e20cdbc20bd3634a3a98b679c4ca2117cc38785e79da87a }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
