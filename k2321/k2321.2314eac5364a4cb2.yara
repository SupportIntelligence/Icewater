
rule k2321_2314eac5364a4cb2
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.2314eac5364a4cb2"
     cluster="k2321.2314eac5364a4cb2"
     cluster_size="7"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="tinba crypt emotet"
     md5_hashes="['347a90b1fc90429e5272493f7a8c1e7e','5f5df9700af9496865d2bb88e1b7f40c','f06cc0ddc2846ce82be9d53d7b5cdede']"

   strings:
      $hex_string = { d4930444149e277377de0e9a3fc17ce5299b350b988dc76cacff488b948f3768f7cc01e1453f49c6a5c3d3a2fe153d99dc7a6134e66aa9edf41874f0ad2dfdcd }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
