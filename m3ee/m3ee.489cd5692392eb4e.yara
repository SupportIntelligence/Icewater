
rule m3ee_489cd5692392eb4e
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3ee.489cd5692392eb4e"
     cluster="m3ee.489cd5692392eb4e"
     cluster_size="251"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ursu filerepmalware malicious"
     md5_hashes="['00600d4f3011a2095d20686be5929306','0393780164db83b2b94f96388f9b2c2c','0cfd4f5b2f596c4af8793ce193400050']"

   strings:
      $hex_string = { 7c328032843288328c32f53327342e345934b434b834bc34c034c434b035e6350f36163623362a367b360a376737003811381d3847386038aa38023909392539 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
