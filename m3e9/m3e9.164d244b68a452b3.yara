
rule m3e9_164d244b68a452b3
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.164d244b68a452b3"
     cluster="m3e9.164d244b68a452b3"
     cluster_size="13"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="cpsg riskware adload"
     md5_hashes="['02c825a9a775748d9a551a914a00b5e5','05a864a58e668772f29fc8306c11945d','e006554b350b286f2d760419b14e394e']"

   strings:
      $hex_string = { 54b1050e02b67c0432203c68e888a08abec9d9e4eba7f85fe908b253d2ed8b480337c4bb19a9110fd53e967949281c69b492da971ebc4ccdf2f96c8589571da2 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
