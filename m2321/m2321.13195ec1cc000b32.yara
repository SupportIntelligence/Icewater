
rule m2321_13195ec1cc000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.13195ec1cc000b32"
     cluster="m2321.13195ec1cc000b32"
     cluster_size="4"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="mira ccpk icgh"
     md5_hashes="['3cde76ced20b88f0f2b78383f6099fac','729bc21845c29b9151ed85d7a5b591d9','d9e2c2b81aedc41a33131a033ccd2b9e']"

   strings:
      $hex_string = { b8008d44096f6c2cfaa4ed92eeff215026025be5f58539904ef405ca43a82a9319a7cc87518eff5fc88f45e4a060c1680dbc1dd742540a1f9d0b9cb504365589 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
