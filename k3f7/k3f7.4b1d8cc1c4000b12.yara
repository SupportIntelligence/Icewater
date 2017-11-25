
rule k3f7_4b1d8cc1c4000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3f7.4b1d8cc1c4000b12"
     cluster="k3f7.4b1d8cc1c4000b12"
     cluster_size="2386"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="likejack faceliker clicker"
     md5_hashes="['00179cb05de5eff57e6441af62ca4e74','001a89ae92b5b3f18837734c7c9e671e','01828a8d27b301280ef6dd7340d9ae3c']"

   strings:
      $hex_string = { 436c69636b4a61636b466253686f7728297b0a2f2f766172207370616e73203d20646f63756d656e742e676574456c656d656e747342795461674e616d652822 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
