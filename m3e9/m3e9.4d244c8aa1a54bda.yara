
rule m3e9_4d244c8aa1a54bda
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.4d244c8aa1a54bda"
     cluster="m3e9.4d244c8aa1a54bda"
     cluster_size="313"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="chinky vobfus wbna"
     md5_hashes="['05fa8954d54f0c4b95df95f774666504','08c9ce244df9ef18488fed7d178c5350','3de37f08f8549b646aff43ccc88cb343']"

   strings:
      $hex_string = { 894590c74588080000008d55888d4da0ff15101040008d5598528d459c506a02ff15ac11400083c40c68acc54300eb528b4df083e10485c974098d4dc0ff1520 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
