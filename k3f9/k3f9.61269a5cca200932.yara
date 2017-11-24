
rule k3f9_61269a5cca200932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3f9.61269a5cca200932"
     cluster="k3f9.61269a5cca200932"
     cluster_size="18"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="sirefef malicious pemalform"
     md5_hashes="['2101a35ab3441ae30d579261841182e9','24a48830c54337a67477040f8b60def1','e04c4ecfee8c866b3a1ccb5285fdafd5']"

   strings:
      $hex_string = { fe3008313e317b31d131e4318f3278331b349e34b034c334c834d234e034ff340a351635233539354335cf36e336f336123724374a3753376c37853728382e38 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
