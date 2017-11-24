
rule n2321_099d6a48c0000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n2321.099d6a48c0000b12"
     cluster="n2321.099d6a48c0000b12"
     cluster_size="136"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="zusy jorik injector"
     md5_hashes="['01cf07a2e5ec2b728a39b4748696f2f9','0368efda2a7f1102fbe02a3f7ae6725e','1e3332438d320e07efcf3924d69107db']"

   strings:
      $hex_string = { 16688654fdd820da3913629f77fe7ac470798ff88809ad1e916efb4a9a009dd9f6b95eec33605657bda54906b00e03c938a141b4fa45433ba31d52af253ce010 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
