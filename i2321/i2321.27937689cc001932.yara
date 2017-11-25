
rule i2321_27937689cc001932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=i2321.27937689cc001932"
     cluster="i2321.27937689cc001932"
     cluster_size="6"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171124"
     license = "RIL-1.0 [Rick's Internet License] "
     family="cosmicduke backdoor razy"
     md5_hashes="['0b24e7cdd55c793753b6c3f048c83640','432f3dc6816a897cb2cb1bf499a7d5e6','a364bdb720a0088063989c6f554eea63']"

   strings:
      $hex_string = { d8337176274a17d3c0d1e1e938c1cd1657e28ce358c7172a73a55aba90d8627274646c6b283e726dd9cfe1bef895fee7785bf367df3df19df1f7e268cccdc4c2 }

   condition:
      
      filesize > 1024 and filesize < 4096
      and $hex_string
}
