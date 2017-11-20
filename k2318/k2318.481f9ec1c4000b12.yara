
rule k2318_481f9ec1c4000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2318.481f9ec1c4000b12"
     cluster="k2318.481f9ec1c4000b12"
     cluster_size="203"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="likejack faceliker html"
     md5_hashes="['00a9a9fcf99ae62d04df67abcd2d739d','01084e1b67f6dc6866850199cbe35261','14e2767af42af48de583ba66f6f23e7b']"

   strings:
      $hex_string = { 55412d33323337333938362d31275d293b0a20205f6761712e70757368285b275f747261636b5061676576696577275d293b0a0a20202866756e6374696f6e28 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
