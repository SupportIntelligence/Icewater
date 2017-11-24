
rule m3e9_29adacc479646f16
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.29adacc479646f16"
     cluster="m3e9.29adacc479646f16"
     cluster_size="340"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="virut virtob chir"
     md5_hashes="['002dc0a941fce79abade725ff32b6552','0147bedf2bc014a79f5344a214808d8e','14f073b8e422492d6ab7434f5439e6c8']"

   strings:
      $hex_string = { 525344536686389c74b974428fc2d84f8d2e1bf203000000653a5c6678313972656c5c57494e4e545f352e325f446570656e645c6d6f7a696c6c615c6f626a2d }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
