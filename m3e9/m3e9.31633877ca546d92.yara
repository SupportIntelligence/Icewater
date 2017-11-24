
rule m3e9_31633877ca546d92
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.31633877ca546d92"
     cluster="m3e9.31633877ca546d92"
     cluster_size="49"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="qvod viking jadtre"
     md5_hashes="['43cd4e86a5f4d83ad94e389bcfc10983','5f8ee0db2e50d714caafb90d4aa33694','bbf5f22685c4e2c3f032f2a5f097412d']"

   strings:
      $hex_string = { 97e31e3afafeaec27686bb3dbc3b5dad387c3184c68944407377221a425815286181707bf1058c494d435928e4edc1cf7eec1b269c903f5ede140f2addd5069b }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
