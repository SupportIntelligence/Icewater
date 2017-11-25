
rule o42d_2994e048c0000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o42d.2994e048c0000b12"
     cluster="o42d.2994e048c0000b12"
     cluster_size="7"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="installmiez extinstall installcore"
     md5_hashes="['031955448b315131960b16e0c274d9f7','0edb0df061727e8662f739b956252fd6','da7c2a139db1a4ce36f0b4196bccff64']"

   strings:
      $hex_string = { bee3f81366e4de4225b98da95f04e2d59116851ead76617fb4ccf50a9dae782ecf64566ebbfd79e67d59af1cf6ec3b323a5d4c698880d1c1589927eb1b55abfe }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
