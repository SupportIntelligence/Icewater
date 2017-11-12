
rule n3f4_31320528d9af4912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3f4.31320528d9af4912"
     cluster="n3f4.31320528d9af4912"
     cluster_size="6"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171111"
     license = "RIL-1.0 [Rick's Internet License] "
     family="malicious heuristic kryptik"
     md5_hashes="['366d3e436b876544f1d56692830887a7','8fb1daeb1ed2816f8bf2823e1181b22c','e1cd1c006adbc870401d373c8c3febfa']"

   strings:
      $hex_string = { 6533754a6b7276302f3178514c4862493267683077424d6448523670543571635a6d384b65426c32517a636e525870794e314546365655676f392b66426d3444 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
