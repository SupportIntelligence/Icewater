
rule m2319_2b9b9599c2200b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2319.2b9b9599c2200b12"
     cluster="m2319.2b9b9599c2200b12"
     cluster_size="4"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="faceliker clicker script"
     md5_hashes="['093e1816e9ee6de6440e844aa977d9bc','981982f60875ed1d91ab4c74ca1d9932','da5bb079b49a1a7497f205bc47956ac7']"

   strings:
      $hex_string = { 4153632f66397465616264694643342f7337322d632f74756d626c725f6d3536383466703254683172776473746c6f315f3530302e6a7067272077696474683d }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
