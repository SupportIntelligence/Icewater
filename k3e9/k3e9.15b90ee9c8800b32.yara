
rule k3e9_15b90ee9c8800b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.15b90ee9c8800b32"
     cluster="k3e9.15b90ee9c8800b32"
     cluster_size="531"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="generickd bublik small"
     md5_hashes="['01e2e82d433fa53b9bff061b1e1d44bc','02771ffda9fc50fed992b927642a325a','15b5b4e72d461414755721761bf9e18e']"

   strings:
      $hex_string = { 5d35b459ed490025004068e8e67dc094adaa4685b89a2540006800e80c47a4ca05423832e825680040004c62e3189d45c23940e80000682533bd884fd381cca0 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
