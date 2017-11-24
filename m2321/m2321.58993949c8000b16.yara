
rule m2321_58993949c8000b16
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.58993949c8000b16"
     cluster="m2321.58993949c8000b16"
     cluster_size="190"
     filetype = "HTML document"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit html script"
     md5_hashes="['0253609bee5fda4f811eac0fb9bb5aca','037ceb8cd5aeace403e57849cd1903a5','1aabd4444a8e2792871699847c5a00f9']"

   strings:
      $hex_string = { aa6c9b7a2f8ec1dd563d9adc2116356a10c84d6d9efce8612b7c64ba079f29fb871d6fef94dac406ae9886521e9288f382f183338145c2085e4e7426bb8d0c41 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
