
rule n2321_339a6886debb0912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n2321.339a6886debb0912"
     cluster="n2321.339a6886debb0912"
     cluster_size="13"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="fileinfector aovhryb delf"
     md5_hashes="['08410c30ac5d35264df4bfa7bef6826d','1c44a0933b7a32a154a4c8497e2d02d3','f109f9f3f4eea626a07393a34c5a5330']"

   strings:
      $hex_string = { ee18f18372e0493953a702b6ceb2c32ba0330c10e97170ec3da1edcc068457b411aed20ecd8a8cb0acbf5941cfca52ded920a317c5bc6b94ef66c16df96e56d6 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
