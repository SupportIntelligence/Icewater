
rule m2321_231896c9cc000b16
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.231896c9cc000b16"
     cluster="m2321.231896c9cc000b16"
     cluster_size="6"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit html script"
     md5_hashes="['067b11b4aa976532b178f614686a2ad6','1ca0cb79229d3ead1e0857d911e805ba','bee4cd61600ef738350d1dedd64a03c1']"

   strings:
      $hex_string = { 8402529395e3d3b826dced2a8b2c0348c9c614b4771dbfba85acd80ca974b95b1ad48773d6f25a285d7f72d74992b6def13861bef3f816c33565746024c54f8d }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
