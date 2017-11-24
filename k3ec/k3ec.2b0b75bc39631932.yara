
rule k3ec_2b0b75bc39631932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3ec.2b0b75bc39631932"
     cluster="k3ec.2b0b75bc39631932"
     cluster_size="9"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="brontok memscan email"
     md5_hashes="['3b85f41862ebdc6c43d7d21de271fb9d','4173fed9cddbb4e115d3d020bc50303a','e1269fa40d1917773b9f44b7fede0231']"

   strings:
      $hex_string = { c181385045b93757744a5f1b78180b30a1dfb1fd7f2bd966a506b448148d4c0118de0b855b6c0d31add872d646036e83e0ffd03bda7306f641278075770f408f }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
